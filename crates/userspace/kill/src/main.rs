// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/kill` — send a signal to a process.
//!
//! Usage:
//!   kill PID [PID ...]            # send SIGTERM (15)
//!   kill -SIGNAME PID [PID ...]   # send the named signal
//!   kill -SIGNUM PID [PID ...]    # send the numbered signal
//!
//! Recognised signal names: HUP INT QUIT KILL TERM CHLD (with or without
//! the `SIG` prefix). Unknown names print an error to stderr and the
//! utility exits with status 1.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/kill.html`

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
        main = sym kill_main,
    );
}

extern "C" fn kill_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_stderr(b"kill: usage: kill [-SIG] PID [PID ...]\n");
        libc::exit(1);
    }

    let mut idx = 1usize;
    let mut sig: i32 = libc::SIGTERM;

    // SAFETY: argv is the kernel-supplied argv array; entries 0..argc are valid C strings.
    let arg1 = unsafe { cstr_at(argv, idx) };
    if !arg1.is_empty() && arg1[0] == b'-' {
        match parse_signal_arg(&arg1[1..]) {
            Some(s) => sig = s,
            None => {
                write_stderr(b"kill: unknown signal\n");
                libc::exit(1);
            }
        }
        idx += 1;
    }

    if idx >= argc {
        write_stderr(b"kill: missing operand\n");
        libc::exit(1);
    }

    let mut had_error = false;
    while idx < argc {
        // SAFETY: argv[idx] is a valid C string for idx < argc.
        let pid_bytes = unsafe { cstr_at(argv, idx) };
        match parse_pid(pid_bytes) {
            Some(pid) => {
                let r = libc::kill(pid, sig);
                if r < 0 {
                    write_stderr(b"kill: failed\n");
                    had_error = true;
                }
            }
            None => {
                write_stderr(b"kill: invalid PID\n");
                had_error = true;
            }
        }
        idx += 1;
    }

    libc::exit(if had_error { 1 } else { 0 })
}

/// SAFETY: Caller must guarantee `idx < argc` and that `argv` is
/// a valid argv array supplied by the kernel.
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

fn parse_pid(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc: i64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as i64)?;
    }
    Some(acc)
}

fn parse_signal_arg(bytes: &[u8]) -> Option<i32> {
    if bytes.is_empty() {
        return None;
    }
    if bytes[0].is_ascii_digit() {
        let mut acc: i32 = 0;
        for &b in bytes {
            if !b.is_ascii_digit() {
                return None;
            }
            acc = acc.checked_mul(10)?.checked_add((b - b'0') as i32)?;
        }
        return Some(acc);
    }
    let name = if bytes.starts_with(b"SIG") {
        &bytes[3..]
    } else {
        bytes
    };
    Some(match name {
        b"HUP" => libc::SIGHUP,
        b"INT" => libc::SIGINT,
        b"QUIT" => libc::SIGQUIT,
        b"KILL" => libc::SIGKILL,
        b"TERM" => libc::SIGTERM,
        b"CHLD" => libc::SIGCHLD,
        _ => return None,
    })
}

fn write_stderr(msg: &[u8]) {
    let mut pos = 0;
    while pos < msg.len() {
        // SAFETY: msg is a valid byte slice; we pass an in-bounds pointer.
        let n = unsafe { libc::write(2, msg[pos..].as_ptr(), msg.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_stderr(b"kill: panic\n");
    libc::exit(1)
}
