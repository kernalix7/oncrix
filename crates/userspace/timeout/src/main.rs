// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/timeout` — run a command with a time limit.
//!
//! Supported usage:
//!
//! ```text
//! timeout [-s SIGNAL] [-k KSECONDS] DURATION COMMAND [ARGS...]
//! ```
//!
//! `DURATION` is a positive whole-second decimal (1..=600). On timeout the
//! parent sends `SIGNAL` (default `SIGTERM`) to the child. If `-k KSECONDS`
//! is set and the child is still alive `KSECONDS` after the initial signal,
//! `SIGKILL` is sent.
//!
//! Exit codes:
//!
//! - Child exited before timeout → its own exit code is forwarded.
//! - Child was signalled (any signal) → `128 + signo` (so `SIGKILL` → 137).
//! - Child reached the timeout → `124` (POSIX timeout exit code).
//!
//! `timeout` is a GNU coreutils extension, not standardised by POSIX.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum supported `DURATION` in seconds. Anything beyond this is
/// rejected to keep the poll loop's iteration count bounded.
const MAX_DURATION_SECS: u64 = 600;
/// Maximum argv slots forwarded to the child command (NULL terminator included).
const ARGV_MAX: usize = 32;
/// `waitpid(2)` flag — return immediately if no child has changed state.
const WNOHANG: i32 = 1;
/// Poll period for the parent's wait loop, in nanoseconds (100 ms).
const POLL_NS: i64 = 100_000_000;
/// Poll periods per second.
const POLLS_PER_SEC: u64 = 10;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym timeout_main,
    );
}

extern "C" fn timeout_main(argc: usize, argv: *const *const u8) -> ! {
    // -------- parse flags --------
    let mut idx = 1usize;
    let mut signal: i32 = libc::SIGTERM;
    let mut kill_after: u64 = 0; // 0 = no SIGKILL escalation

    while idx < argc {
        // SAFETY: idx < argc and argv was provided by the kernel.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-s" {
            idx += 1;
            if idx >= argc {
                fail(b"timeout: -s needs SIGNAL\n");
            }
            // SAFETY: idx < argc.
            let v = unsafe { cstr_at(argv, idx) };
            signal = match parse_signal(v) {
                Some(s) => s,
                None => fail(b"timeout: invalid signal\n"),
            };
            idx += 1;
            continue;
        }
        if arg == b"-k" {
            idx += 1;
            if idx >= argc {
                fail(b"timeout: -k needs SECONDS\n");
            }
            // SAFETY: idx < argc.
            let v = unsafe { cstr_at(argv, idx) };
            kill_after = match parse_u64(v) {
                Some(n) if n > 0 && n <= MAX_DURATION_SECS => n,
                _ => fail(b"timeout: invalid -k value\n"),
            };
            idx += 1;
            continue;
        }
        // First non-flag argument is the DURATION.
        break;
    }

    if idx >= argc {
        fail(b"timeout: missing DURATION\n");
    }
    // SAFETY: idx < argc.
    let dur_str = unsafe { cstr_at(argv, idx) };
    idx += 1;
    let duration = match parse_u64(dur_str) {
        Some(n) if n > 0 && n <= MAX_DURATION_SECS => n,
        _ => fail(b"timeout: invalid DURATION\n"),
    };

    if idx >= argc {
        fail(b"timeout: missing COMMAND\n");
    }

    // -------- build child argv --------
    // argv entries are NUL-terminated strings already in our address space
    // (sys_execve set them up), so we forward the pointers directly.
    let mut child_argv: [*const u8; ARGV_MAX] = [core::ptr::null(); ARGV_MAX];
    let mut slot = 0usize;
    while idx < argc && slot < ARGV_MAX - 1 {
        // SAFETY: idx < argc; argv[idx] is a valid C-string pointer.
        let p = unsafe { *argv.add(idx) };
        if p.is_null() {
            break;
        }
        child_argv[slot] = p;
        slot += 1;
        idx += 1;
    }
    if idx < argc {
        fail(b"timeout: too many arguments\n");
    }
    // child_argv[slot] stays NULL — POSIX-required terminator.

    let envp: [*const u8; 1] = [core::ptr::null()];
    let path = child_argv[0];

    // -------- fork the child --------
    let pid = libc::fork();
    if pid < 0 {
        fail(b"timeout: fork failed\n");
    }
    if pid == 0 {
        // SAFETY: path is a NUL-terminated argv string from the kernel;
        // child_argv ends in NULL; envp is a single NULL terminator.
        unsafe { libc::execve(path, child_argv.as_ptr(), envp.as_ptr()) };
        // execve only returns on failure.
        write_all(2, b"timeout: exec failed\n");
        libc::exit(127);
    }

    // -------- parent poll loop --------
    // Cap iterations at duration + kill_after to keep the loop bounded.
    let timeout_polls = duration.saturating_mul(POLLS_PER_SEC);
    let kill_polls = kill_after.saturating_mul(POLLS_PER_SEC);
    let total_polls = timeout_polls.saturating_add(kill_polls);

    let mut polls: u64 = 0;
    let mut signal_sent = false;
    let mut kill_sent = false;

    loop {
        let mut status: i32 = 0;
        // SAFETY: pid is the child PID returned by fork; status is a stack
        // i32 owned for this call; WNOHANG makes this non-blocking.
        let w = unsafe { libc::waitpid(pid, &mut status as *mut i32, WNOHANG) };
        if w < 0 {
            // EINTR isn't surfaced by ONCRIX nanosleep, so any error here
            // is unrecoverable — report and bail.
            fail(b"timeout: waitpid failed\n");
        }
        if w == pid {
            // Child reaped.
            if libc::wifexited(status) {
                let code = libc::wexitstatus(status);
                if signal_sent {
                    // Child exited after we signalled it; still flag this
                    // as a timeout per GNU coreutils behaviour.
                    libc::exit(124);
                }
                libc::exit(code);
            }
            if libc::wifsignaled(status) {
                let sig = libc::wtermsig(status);
                libc::exit(128 + sig);
            }
            // Unknown wait status — treat as failure.
            libc::exit(125);
        }

        // Child still running. Decide whether to (re)signal.
        if !signal_sent && polls >= timeout_polls {
            // SAFETY: pid is a live child PID; kill is total-safe.
            let _ = libc::kill(pid, signal);
            signal_sent = true;
        } else if signal_sent
            && !kill_sent
            && kill_after > 0
            && polls >= timeout_polls.saturating_add(kill_polls)
        {
            // SAFETY: pid is a live child PID.
            let _ = libc::kill(pid, libc::SIGKILL);
            kill_sent = true;
        }

        // Hard upper bound: even after SIGKILL the kernel should reap
        // within a poll or two; give it a generous extra second.
        if polls > total_polls.saturating_add(POLLS_PER_SEC + 1) {
            // Best-effort: stop waiting. Report 124 since we timed out.
            libc::exit(124);
        }

        let req = libc::Timespec {
            tv_sec: 0,
            tv_nsec: POLL_NS,
        };
        // SAFETY: req is a stack-allocated valid Timespec; rem is null.
        unsafe { libc::nanosleep(&req, core::ptr::null_mut()) };
        polls = polls.saturating_add(1);
    }
}

/// Parse a signal name (`TERM`, `KILL`, `INT`, `HUP`, with optional `SIG`
/// prefix) or a small positive decimal signal number. Returns `None` on
/// unrecognised input.
fn parse_signal(s: &[u8]) -> Option<i32> {
    if s.is_empty() {
        return None;
    }
    if s[0].is_ascii_digit() {
        let n = parse_u64(s)?;
        if n == 0 || n > 64 {
            return None;
        }
        return Some(n as i32);
    }
    // Accept optional "SIG" prefix.
    let name = if s.len() > 3 && s[0] == b'S' && s[1] == b'I' && s[2] == b'G' {
        &s[3..]
    } else {
        s
    };
    match name {
        b"TERM" => Some(libc::SIGTERM),
        b"KILL" => Some(libc::SIGKILL),
        b"INT" => Some(libc::SIGINT),
        b"HUP" => Some(libc::SIGHUP),
        _ => None,
    }
}

/// Parse a non-negative decimal `u64` from `buf`. Returns `None` on empty
/// input or any non-digit character (and on arithmetic overflow).
fn parse_u64(buf: &[u8]) -> Option<u64> {
    if buf.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &b in buf {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(n)
}

/// Walk an argv slot and return the underlying NUL-terminated bytes.
///
/// # Safety
///
/// Caller guarantees `idx < argc` and that `argv` is the argv pointer
/// supplied by the kernel (each entry is a NUL-terminated C string).
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

fn fail(msg: &[u8]) -> ! {
    write_all(2, msg);
    libc::exit(1)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"timeout: panic\n");
    libc::exit(1)
}
